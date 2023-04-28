#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt_ta.h>

#define MY_NAME_MAX 30
#define MY_FILE_MAX 86
#define MY_OUTPUT_LEN 129

int evaluate_command(int argc, char* argv[], char* crypto_type, char* option, char inputtext[], char keytext[])
{
	const char caesar_str[] = "Caesar";
	const char rsa_str[] = "RSA";
	char input_file[MY_NAME_MAX];
	char input_key_file[MY_NAME_MAX];
	FILE* input_fp;
	FILE* input_key_fp;
	int input_count = 0;
	int key_count = 0;
	int type_count = 1;

	if (argc > 4)
	{
		printf("[ERROR] Too much Argument! Format must be \"TEEencrypt ((-e [input file] [crypto algorithm]) | (-d [input file] [key file]))\"\n");
		return -1;
	}

	// Parse Argument
	for (int i = 1; i < argc; i++)
	{
		if (strlen(argv[i]) == 2 && argv[i][0] == '-' && argv[i][1] == 'e')
		{
			if (argc < i+2)
			{
				printf("[ERROR] No input file!\n");
				return -1;
			}
			*option = 'e';
			input_count = 1;
			type_count = 1;
		} else if (strlen(argv[i]) == 2 && argv[i][0] == '-' && argv[i][1] == 'd')
		{
			if (argc < i+2)
			{
				printf("[ERROR] No input file!\n");
				return -1;
			}
			if (argc < i+3)
			{
				printf("[ERROR] No key file!\n");
				return -1;
			}
			*option = 'd';
			input_count = 1;
			key_count = 1;
		} else if (input_count > 0)
		{
			strcpy(input_file, argv[i]);
			input_count--;
		} else if (key_count > 0)
		{
			strcpy(input_key_file, argv[i]);
			key_count--;
		} else if (type_count > 0)
		{
			if (argc == 4 && strcmp(caesar_str, argv[i]) == 0)
			{
				*crypto_type = 'c';
			}
			if (argc == 4 && strcmp(rsa_str, argv[i]) == 0)
			{
				*crypto_type = 'r';
			}
			type_count--;
		}
	}

	input_fp = fopen(input_file, "r");
	if (input_fp == NULL)
	{
		printf("[ERROR] No such input file!\n");
		return -1;
	}
	while(!feof(input_fp))
	{
		char aline[MY_FILE_MAX];
		if(fgets(aline, MY_FILE_MAX, input_fp) == NULL)
			break;
		if(strlen(inputtext) + strlen(aline) > MY_FILE_MAX-1)
		{
			printf("[ERROR] Too big Input File!\n");
			return -1;
		}
		strcat(inputtext, aline);
	}
	fclose(input_fp);

	if (*option == 'd')
	{
		input_key_fp = fopen(input_key_file, "r");
		if (input_key_fp == NULL)
		{
			printf("[ERROR] No such key file!\n");
			return -1;
		}
		while(!feof(input_key_fp))
		{
			char aline[MY_FILE_MAX];
			if(fgets(aline, MY_FILE_MAX, input_key_fp) == NULL)
				break;
			if(strlen(inputtext) + strlen(aline) > MY_FILE_MAX-1)
			{
				printf("[ERROR] Too big Key File!\n");
				return -1;
			}
			strcat(keytext, aline);
		}
		fclose(input_key_fp);
	}
	return 0;
}

void prepare_ta_session(TEEC_Context* ctx, TEEC_Session* sess)
{
	uint32_t err_origin;
	TEEC_Result res;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;

	res = TEEC_InitializeContext(NULL, ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "\nTEEC_InitializeContext failed with code 0x%x\n", res);

	res = TEEC_OpenSession(ctx, sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "\nTEEC_Opensession failed with code 0x%x origin 0x%x\n", res, err_origin);
}

void write_output_file(char name[], char buffer[])
{
	FILE* fp = fopen(name, "w");
	fputs(buffer, fp);
	fclose(fp);
}

// ------------------------------------------------------------------------------- //
// ------------------------------- Caesar ---------------------------------------- //
// ------------------------------------------------------------------------------- //
void prepare_caesar_op(TEEC_Operation *op, char inout[], int key)
{
	memset(op, 0, sizeof(*op));

	op->paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, TEEC_VALUE_INOUT,
					 TEEC_NONE, TEEC_NONE);
	op->params[0].tmpref.buffer = inout;
	op->params[0].tmpref.size = MY_FILE_MAX;
	op->params[1].value.a = key;
}

void caesar_encrypt(TEEC_Session* sess, char textbuffer[], char keybuffer[])
{
	TEEC_Operation op;
	uint32_t err_origin;
	TEEC_Result res;

	prepare_caesar_op(&op, textbuffer, 0);
	res = TEEC_InvokeCommand(sess, TA_TEEencrypt_CMD_CAESAR_ENCRYPT, &op,
				 &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "\nTEEC_InvokeCommand(TA_TEEencrypt_CMD_CAESAR_ENCRYPT) failed 0x%x origin 0x%x\n",
			res, err_origin);

	// Result //
	write_output_file("ciphertext.txt", op.params[0].tmpref.buffer); // Cipher Text
	sprintf(keybuffer, "%d", op.params[1].value.a);
	write_output_file("erk.txt", keybuffer); // Encrypted Random Key(ERK)
}
void caesar_decrypt(TEEC_Session* sess, char textbuffer[], char keybuffer[])
{
	TEEC_Operation op;
	uint32_t err_origin;
	TEEC_Result res;

	prepare_caesar_op(&op, textbuffer, atoi(keybuffer));
	res = TEEC_InvokeCommand(sess, TA_TEEencrypt_CMD_CAESAR_DECRYPT, &op,
				 &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "\nTEEC_InvokeCommand(TA_TEEencrypt_CMD_CAESAR_DECRYPT) failed 0x%x origin 0x%x\n",
			res, err_origin);

	// Result //
	write_output_file("plaintext.txt", op.params[0].tmpref.buffer); // Plain Text
	sprintf(keybuffer, "%d", op.params[1].value.a);
	write_output_file("drk.txt", keybuffer); // Decrypted Random Key(DRK)
}


// ------------------------------------------------------------------------------- //
// ---------------------------------- RSA ---------------------------------------- //
// ------------------------------------------------------------------------------- //

void prepare_rsa_op(TEEC_Operation *op, char in[], char out[])
{
	memset(op, 0, sizeof(*op));

	op->paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE, TEEC_NONE);
	op->params[0].tmpref.buffer = in;
	op->params[0].tmpref.size = MY_FILE_MAX;
	op->params[1].tmpref.buffer = out;
	op->params[1].tmpref.size = MY_OUTPUT_LEN;
}
void rsa_gen_keys(TEEC_Session* sess) {
	TEEC_Result res;

	res = TEEC_InvokeCommand(sess, TA_TEEencrypt_CMD_RSA_GENKEY, NULL, NULL);
	if (res != TEEC_SUCCESS)
		errx(1, "\nTEEC_InvokeCommand(TA_TEEencrypt_CMD_RSA_GENKEY) failed %#x\n", res);
	printf("\n=========== Keys already generated. ==========\n");
}
void rsa_encrypt(TEEC_Session* sess, char inputbuffer[])
{
	TEEC_Operation op;
	uint32_t err_origin;
	TEEC_Result res;

	char outputbuffer[MY_OUTPUT_LEN] = {0,};

	prepare_rsa_op(&op, inputbuffer, outputbuffer);
	printf("\n============ RSA ENCRYPT CA SIDE ============\n");

	res = TEEC_InvokeCommand(sess, TA_TEEencrypt_CMD_RSA_ENCRYPT,
				 &op, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "\nTEEC_InvokeCommand(TA_TEEencrypt_CMD_RSA_ENCRYPT) failed 0x%x origin 0x%x\n",
			res, err_origin);
	
	// Result //

	printf("\nEncrypted data: %s\nEncrypted data length: %d\n", op.params[1].tmpref.buffer, strlen(op.params[1].tmpref.buffer));
	write_output_file("ciphertext.txt", op.params[1].tmpref.buffer); // Cipher Text
}

// ------------------------------------------------------------------------------- //
// ---------------------------------- MAIN --------------------------------------- //
// ------------------------------------------------------------------------------- //
int main(int argc, char* argv[])
{
	TEEC_Context ctx;
	TEEC_Session sess;

	char crypto_type = 'c'; // 'c' -> Caesar, 'r' -> RSA
	char option = '\0'; // 'e' -> encrypt, 'd' -> decrypt
	char textbuffer[MY_FILE_MAX] = {0,};
	char keybuffer[MY_FILE_MAX] = {0,};

	int eval_result = evaluate_command(argc, argv, &crypto_type, &option, textbuffer, keybuffer);
	printf("\n================Command Evaluate================\n");
	printf("crypto type: %c\noption: %c\ninputtext: %s\nkeytext: %s\n", crypto_type, option, textbuffer, keybuffer);
	
	if (eval_result)
	{
		printf("[NOTICE] Terminating by wrong command.\n");
		return -1;
	}
	
	// -------------Session Start----------------- //
	prepare_ta_session(&ctx, &sess);

	if (option == 'e' && crypto_type == 'c')
	{
		caesar_encrypt(&sess, textbuffer, keybuffer);
	} else if (option == 'e' && crypto_type == 'r')
	{
		rsa_gen_keys(&sess);
		rsa_encrypt(&sess, textbuffer);
	} else if (option == 'd')
	{
		caesar_decrypt(&sess, textbuffer, keybuffer);
	}

	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);
	// ---------------Session End----------------- //

	return 0;
}
