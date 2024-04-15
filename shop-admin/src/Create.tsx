import * as React from 'react';
import { Create, SimpleForm, TextInput, DateInput, required, NumberInput, SelectInput, ImageInput, ImageField } from 'react-admin';

export const CustomerCreate = () => (
    <Create>
        <SimpleForm>
            <TextInput source="username" validate={[required()]} label="username"/>
            <TextInput source="password" validate={[required()]} label="password"/>
            <TextInput source="phone_number" multiline={true} label="phone_number" validate={[required()]}  />
            <TextInput source="email" multiline={true} label="email" validate={[required()]} />
            <TextInput source="role" multiline={true} label="role" validate={[required()]} />
        </SimpleForm>
    </Create>
);


export const ProductCreate = (props:any) => (
    <Create {...props}>
        <SimpleForm>
            <TextInput source="name" validate={[required()]} />
            <TextInput multiline source="description" validate={[required()]} />
            <NumberInput source="price" validate={[required()]} />
            <SelectInput source="category_id" choices={[
                { id: '1', name: 'Category 1' },
                { id: '2', name: 'Category 2' },
                // Add other categories as needed
            ]} validate={[required()]} />
            <ImageInput source="image" label="Product Image" accept="image/*">
                <ImageField source="src" title="title" />
            </ImageInput>
        </SimpleForm>
    </Create>

        )



export const CategoryCreate = (props:any) => (
    <Create {...props}>
        <SimpleForm>
            <TextInput source="name" label="Name" validate={[required()]} />
            <TextInput multiline source="description" label="Description" validate={[required()]} />
            <TextInput source="parent_category_id" label="Parent Category ID" />
            <DateInput source="created_at" label="Creation Date" />
        </SimpleForm>
    </Create>
);
